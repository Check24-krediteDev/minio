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
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// TestQueryStringBypassCVE tests the CVE-2026-41145 fix for query-string authentication bypass.
//
// Vulnerability Description:
// - Requests with X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER
// - Combined with query-string credentials (X-Amz-Credential, X-Amz-Signature)
// - But no Authorization header
// - Would bypass signature verification due to auth type confusion
//
// Expected Behavior After Fix:
// - Attack requests should return 403 Forbidden (signature verification enforced)
// - Auth type detection should prioritize presigned over unsigned trailer
func (s *TestSuiteCommon) TestQueryStringBypassCVE(c *check) {
	c.Helper()

	// Generate a random bucket name.
	bucketName := getRandomBucketName()

	// Step 1: Create bucket with legitimate signed request
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	// Execute the bucket creation request.
	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Step 2: Craft malicious PUT request demonstrating CVE-2026-41145
	objectName := "cve-2026-41145-test-object.txt"
	testData := []byte("This should NOT upload without proper signature verification!")

	// Create a proper presigned request first
	req, err := http.NewRequest(http.MethodPut, getPutObjectURL(s.endPoint, bucketName, objectName), bytes.NewReader(testData))
	c.Assert(err, nil)
	req.ContentLength = int64(len(testData))

	// Create valid presigned URL (this should work normally)
	expires := int64(300) // 5 minutes
	err = preSignV4(req, s.accessKey, s.secretKey, expires)
	c.Assert(err, nil)

	// Now perform the attack: Replace content-sha256 with unsigned trailer
	// This creates the vulnerability condition:
	// 1. Query has presigned credentials (X-Amz-Credential, X-Amz-Signature, etc.)
	// 2. But X-Amz-Content-Sha256 = STREAMING-UNSIGNED-PAYLOAD-TRAILER
	// 3. No Authorization header
	// Result: auth type becomes authTypeStreamingUnsignedTrailer instead of authTypePresigned

	req.Header.Set("X-Amz-Content-Sha256", unsignedPayloadTrailer)
	req.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprintf("%d", len(testData)))
	req.Header.Set("Content-Encoding", "aws-chunked")

	// Key vulnerability: The presigned signature in query is for UNSIGNED-PAYLOAD
	// but we changed to STREAMING-UNSIGNED-PAYLOAD-TRAILER without re-signing
	// This should be rejected, but due to auth type confusion, signature check is bypassed

	// Execute the malicious request
	response, err = s.client.Do(req)
	c.Assert(err, nil)

	// VULNERABILITY TEST: After fix, attack should be blocked
	// Attack should now fail with signature verification error
	c.Assert(response.StatusCode, http.StatusForbidden)
}

// TestExtractHandlerBypassCVE tests the CVE-2026-41145 fix for PutObjectExtractHandler bypass.
//
// Vulnerability Description:
// - PutObjectExtractHandler switch statement was missing authTypeStreamingUnsignedTrailer case
// - Requests using unsigned trailer authentication would bypass signature verification entirely
// - This created a complete authentication bypass for extract operations
//
// Expected Behavior After Fix:
// - Extract handler should include proper authTypeStreamingUnsignedTrailer case
// - All unsigned trailer requests should undergo signature verification
// - Attack requests should return 403 Forbidden
func (s *TestSuiteCommon) TestExtractHandlerBypassCVE(c *check) {
	c.Helper()

	// Generate a random bucket name.
	bucketName := getRandomBucketName()

	// Step 1: Create bucket with legitimate signed request
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)

	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)

	// Step 2: Test PutObjectExtractHandler with unsigned trailer bypass
	objectName := "cve-2026-41145-extract-test.zip"
	testData := []byte("PK\x03\x04test-archive-content-that-should-not-extract")

	// Create extract URL with proper presigned request
	putURL := getPutObjectURL(s.endPoint, bucketName, objectName)
	parsedURL, err := url.Parse(putURL)
	c.Assert(err, nil)

	// Add extract=true parameter to trigger PutObjectExtractHandler
	query := parsedURL.Query()
	query.Set("extract", "true")
	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequest(http.MethodPut, parsedURL.String(), bytes.NewReader(testData))
	c.Assert(err, nil)
	req.ContentLength = int64(len(testData))

	// Create valid presigned URL for extract operation
	expires := int64(300)
	err = preSignV4(req, s.accessKey, s.secretKey, expires)
	c.Assert(err, nil)

	// Attack: Change to unsigned trailer after signing
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayloadTrailer)
	req.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprintf("%d", len(testData)))
	req.Header.Set("Content-Encoding", "aws-chunked")

	// Extract handler vulnerability: Missing authTypeStreamingUnsignedTrailer case
	// This should fail signature verification but may be bypassed entirely

	// Execute the malicious extract request
	response, err = s.client.Do(req)
	c.Assert(err, nil)

	// VULNERABILITY TEST: After fix, extract handler attack should be blocked
	// Attack should now fail with signature verification error
	c.Assert(response.StatusCode, http.StatusForbidden)
}

// TestMixedAuthMethodsCVE demonstrates auth type confusion where requests
// with both STREAMING-UNSIGNED-PAYLOAD-TRAILER and query credentials
// get classified as unsigned trailer instead of presigned, bypassing verification.
func (s *TestSuiteCommon) TestMixedAuthMethodsCVE(c *check) {
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

	// Step 2: Test auth type confusion
	objectName := "cve-2026-41145-mixed-auth.txt"
	testData := []byte("Mixed auth method confusion test")

	putURL := getPutObjectURL(s.endPoint, bucketName, objectName)
	parsedURL, err := url.Parse(putURL)
	c.Assert(err, nil)

	now := UTCNow()
	credential := fmt.Sprintf("%s/%s/us-east-1/s3/aws4_request",
		s.accessKey, now.Format(yyyymmdd))

	// Add complete presigned query parameters
	query := parsedURL.Query()
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", credential)
	query.Set("X-Amz-Date", now.Format(iso8601Format))
	query.Set("X-Amz-Expires", "300")
	query.Set("X-Amz-SignedHeaders", "host;x-amz-content-sha256")
	query.Set("X-Amz-Signature", "fakesignaturethatshouldfailvalidation")

	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequest(http.MethodPut, parsedURL.String(), nil)
	c.Assert(err, nil)

	req.Body = io.NopCloser(bytes.NewReader(testData))
	req.ContentLength = int64(len(testData))

	// The key issue: Both unsigned trailer marker AND query credentials
	// getRequestAuthType should return authTypeStreamingUnsignedTrailer
	// even though query credentials are present
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayloadTrailer)
	req.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprintf("%d", len(testData)))
	req.Header.Set("Content-Encoding", "aws-chunked")

	// Also add Authorization header with different/conflicting signature
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=host;x-amz-content-sha256, Signature=conflictingsignature",
		credential)
	req.Header.Set("Authorization", authHeader)

	// Execute request with mixed auth methods
	response, err = s.client.Do(req)
	c.Assert(err, nil)

	// This test documents current behavior - may succeed due to auth confusion
	// The specific expected status depends on which auth path is taken
	// Currently this should fail due to signature mismatch, but the failure
	// mode demonstrates the auth type confusion issue
	c.Assert(response.StatusCode != http.StatusOK || response.StatusCode == http.StatusBadRequest,
		"Mixed auth methods should have consistent rejection behavior")
}
