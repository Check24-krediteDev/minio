// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"io"
	"net/http"

	"github.com/minio/minio-go/v7/pkg/signer"
)

// TestLegitimateUnsignedTrailer ensures that valid unsigned trailer requests
// continue to work after fixing CVE-2026-41145.
//
// This represents legitimate use of STREAMING-UNSIGNED-PAYLOAD-TRAILER
// without query credentials - should always PASS.
func (s *TestSuiteCommon) TestLegitimateUnsignedTrailer(c *check) {
	c.Helper()

	// Generate a random bucket name.
	bucketName := getRandomBucketName()

	// Step 1: Create bucket with signed request
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Step 2: Legitimate unsigned trailer request (similar to existing TestUnsignedCVE pattern)
	objectName := "legitimate-unsigned-trailer.txt"
	testData := []byte("This is a legitimate unsigned trailer request")

	req, err := http.NewRequest(http.MethodPut, getPutObjectURL(s.endPoint, bucketName, objectName), nil)
	c.Assert(err, nil)

	req.Body = io.NopCloser(bytes.NewReader(testData))
	req.ContentLength = int64(len(testData))

	// Set up legitimate trailer
	req.Trailer = http.Header{}
	req.Trailer.Set("x-amz-checksum-crc32", "rK0DXg==")

	now := UTCNow()

	// Use MinIO SDK helper for proper unsigned streaming setup
	req = signer.StreamingUnsignedV4(req, "", int64(len(testData)), now)

	// This creates a legitimate unsigned trailer request with proper Authorization header
	// containing valid signature for unsigned trailer payload

	// Execute legitimate request
	response, err = s.client.Do(req)
	c.Assert(err, nil)

	// This should always succeed - legitimate unsigned trailer usage
	c.Assert(response.StatusCode, http.StatusOK)
}

// TestValidPresignedRequest ensures that properly signed presigned requests
// continue to work after fixing CVE-2026-41145.
//
// This should always PASS - represents legitimate presigned URL usage.
func (s *TestSuiteCommon) TestValidPresignedRequest(c *check) {
	c.Helper()

	// Generate a random bucket name.
	bucketName := getRandomBucketName()

	// Step 1: Create bucket
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Step 2: Create a valid presigned PUT request
	objectName := "legitimate-presigned-object.txt"
	testData := []byte("This is uploaded via legitimate presigned URL")

	// Build the base PUT URL
	putURL := getPutObjectURL(s.endPoint, bucketName, objectName)

	req, err := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(testData))
	c.Assert(err, nil)
	req.ContentLength = int64(len(testData))

	// Create a properly signed presigned request using existing helper
	expires := int64(300) // 5 minutes
	err = preSignV4(req, s.accessKey, s.secretKey, expires)
	c.Assert(err, nil)

	// Execute the valid presigned request
	response, err = s.client.Do(req)
	c.Assert(err, nil)

	// Valid presigned requests should always succeed
	c.Assert(response.StatusCode, http.StatusOK)
}

// TestValidAuthorizationHeader ensures that standard Authorization header
// requests continue to work after fixing CVE-2026-41145.
//
// This should always PASS - represents standard S3 API usage.
func (s *TestSuiteCommon) TestValidAuthorizationHeader(c *check) {
	c.Helper()

	// Generate a random bucket name.
	bucketName := getRandomBucketName()

	// Step 1: Create bucket
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Step 2: Standard PUT with Authorization header
	objectName := "standard-auth-header-object.txt"
	testData := []byte("Standard S3 PUT with Authorization header")

	// Use the standard test helper for signed requests
	request, err = newTestSignedRequest(http.MethodPut,
		getPutObjectURL(s.endPoint, bucketName, objectName),
		int64(len(testData)), bytes.NewReader(testData),
		s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	// Execute standard signed request
	response, err = s.client.Do(request)
	c.Assert(err, nil)

	// Standard Authorization header requests should always work
	c.Assert(response.StatusCode, http.StatusOK)
}

// TestValidStreamingSignedRequest ensures that legitimate streaming signed requests
// continue to work after fixing CVE-2026-41145.
//
// This should always PASS - represents legitimate streaming upload usage.
func (s *TestSuiteCommon) TestValidStreamingSignedRequest(c *check) {
	c.Helper()

	// Generate a random bucket name.
	bucketName := getRandomBucketName()

	// Step 1: Create bucket
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Step 2: Valid streaming signed request (not unsigned trailer)
	objectName := "streaming-signed-object.txt"
	testData := []byte("Valid streaming signed upload content")

	// Use existing helper for streaming signed requests (with chunkSize)
	request, err = newTestStreamingSignedRequest(http.MethodPut,
		getPutObjectURL(s.endPoint, bucketName, objectName),
		int64(len(testData)), 64*1024, bytes.NewReader(testData),
		s.accessKey, s.secretKey)
	c.Assert(err, nil)

	// Execute streaming signed request
	response, err = s.client.Do(request)
	c.Assert(err, nil)

	// Streaming signed requests should always work
	c.Assert(response.StatusCode, http.StatusOK)
}

// TestMultipartUploadAuthentication ensures that multipart upload authentication
// continues to work properly after fixing CVE-2026-41145.
//
// This should always PASS - represents legitimate multipart usage.
func (s *TestSuiteCommon) TestMultipartUploadAuthentication(c *check) {
	c.Helper()

	// Generate a random bucket name.
	bucketName := getRandomBucketName()

	// Step 1: Create bucket
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Step 2: Initiate multipart upload
	objectName := "multipart-auth-test.txt"

	request, err = newTestSignedRequest(http.MethodPost,
		getNewMultipartURL(s.endPoint, bucketName, objectName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err = s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Extract upload ID from response
	uploadID := response.Header.Get("X-Amz-Upload-Id")
	c.Assert(uploadID != "", true)

	// Step 3: Upload a part with proper authentication
	partData := []byte("Multipart upload part with proper authentication")

	request, err = newTestSignedRequest(http.MethodPut,
		getPartUploadURL(s.endPoint, bucketName, objectName, uploadID, "1"),
		int64(len(partData)), bytes.NewReader(partData),
		s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err = s.client.Do(request)
	c.Assert(err, nil)

	// Multipart part upload should succeed with proper auth
	c.Assert(response.StatusCode, http.StatusOK)

	etag := response.Header.Get("ETag")
	c.Assert(etag != "", true)

	// Step 4: Abort multipart upload (cleanup)
	request, err = newTestSignedRequest(http.MethodDelete,
		getAbortMultipartUploadURL(s.endPoint, bucketName, objectName, uploadID),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err = s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusNoContent)
}
