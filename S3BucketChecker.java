package com.cloudsecurityscanner;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.*;

import java.util.List;

public class S3BucketChecker {

    private final AmazonS3 s3Client;

    public S3BucketChecker() {
        s3Client = AmazonS3Client.builder()
                .withCredentials(new ProfileCredentialsProvider())
                .build();
    }

    public void checkS3BucketPermissions() {
        System.out.println("Checking S3 Buckets for public access...");

        List<Bucket> buckets = s3Client.listBuckets();
        for (Bucket bucket : buckets) {
            BucketAcl acl = s3Client.getBucketAcl(bucket.getName());
            List<Grant> grants = acl.getGrantsAsList();

            for (Grant grant : grants) {
                if (grant.getGrantee().getURI() != null && grant.getGrantee().getURI().equals("http://acs.amazonaws.com/groups/global/AllUsers")) {
                    System.out.println("Warning: Public access found on bucket: " + bucket.getName());
                }
            }
        }
    }
}
