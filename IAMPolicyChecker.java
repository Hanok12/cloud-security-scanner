package com.cloudsecurityscanner;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.iam.AmazonIdentityManagement;
import com.amazonaws.services.iam.AmazonIdentityManagementClient;
import com.amazonaws.services.iam.model.*;

import java.util.List;

public class IAMPolicyChecker {

    private final AmazonIdentityManagement iam;

    public IAMPolicyChecker() {
        iam = AmazonIdentityManagementClient.builder()
                .withCredentials(new ProfileCredentialsProvider())
                .build();
    }

    public void checkIAMPolicies() {
        System.out.println("Checking IAM Policies for overly permissive roles...");

        ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest().withUserName("example-user");
        ListAttachedUserPoliciesResponse response = iam.listAttachedUserPolicies(request);

        for (AttachedPolicy policy : response.getAttachedPolicies()) {
            if (policy.getPolicyName().equals("AdministratorAccess")) {
                System.out.println("Warning: The user has admin access!");
            }
        }
    }
}
