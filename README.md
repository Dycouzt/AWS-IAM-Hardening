# Securing AWS IAM: A Practical Hardening Project

This project demonstrates the hands-on implementation of essential AWS Identity and Access Management (IAM) security principles. The goal was to build a secure and compliant AWS environment by applying least privilege, enforcing Multi-Factor Authentication (MFA), and establishing comprehensive logging, thereby hardening the account against unauthorized access and reducing the overall attack surface.

## Project Scope

The scope of this hardening project included the following key security objectives:

*   **Root Account Security:** Securing the AWS root user to prevent misuse.
*   **Principle of Least Privilege (PoLP):** Ensuring IAM users and entities are granted only the minimum permissions required to perform their tasks. This was implemented through:
    *   **Read-Only Policies:** Restricting users to only view resources.
    *   **Role-Based Access Control (RBAC):** Granting permissions temporarily via IAM Roles.
    *   **Conditional Policies:** Restricting access based on context, such as source IP address.
*   **MFA Enforcement:** Requiring a second factor of authentication for all IAM users to enhance account protection.
*   **Scalable Permissions:** Using IAM Groups to efficiently manage permissions for multiple users.
*   **Logging and Monitoring:** Configuring AWS CloudTrail to create an immutable audit trail of all actions performed in the account.
*   **Validation:** Actively testing and verifying that all security controls work as intended.

## Implementation Steps

The following steps were executed to harden the AWS account:

1.  **Initial Environment Setup**
    *   A test S3 bucket (`cloud-sec-project-test-bucket`) and an EC2 instance (`CloudSecEC2`) were created to serve as resources for permission testing.
    *   A **Zero-Spend Budget** was configured in AWS Billing and Cost Management to prevent unexpected costs.

2.  **Root User Hardening**
    *   MFA was enabled for the root user, ensuring that the most powerful account credential was protected from compromise.

3.  **IAM User & Group Configuration**
    *   Three test IAM users were created: `TestUser1`, `TestUser2`, and `TestUser3`.
    *   Each user was configured with an auto-generated password and was required to reset it upon first login.
    *   An IAM group named `CloudSecEC2ReadOnly` was created with a policy granting read-only access to EC2 instances. `TestUser1` and `TestUser3` were added to this group, demonstrating scalable permission management.

4.  **Applying the Principle of Least Privilege (PoLP)**
    *   **Read-Only Access:** `TestUser1` was assigned a custom IAM policy granting only `s3:Get*` and `s3:List*` permissions to the test S3 bucket. Tests confirmed the user could list objects but was denied permission to upload or delete.
    *   **Role-Based Access (RBAC):** An IAM Role (`S3FullAccessRole`) was created with full S3 permissions. `TestUser2` was given a policy allowing it to assume this role (`sts:AssumeRole`). The user had no S3 access by default but gained full permissions after switching to the role in the AWS Console.
    *   **Conditional Access:** `TestUser3` was assigned a policy that allowed S3 actions only if the request originated from a specific IP address, using a `Condition` block in the IAM policy.

5.  **MFA Enforcement**
    *   MFA was enabled for all three IAM users using a virtual authenticator app.
    *   A custom IAM policy was deployed and attached to all users to explicitly deny all actions if the session was not authenticated using MFA. This ensures MFA cannot be bypassed.

    **MFA Enforcement Policy (JSON):**
    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "BoolIfExists": {
                        "aws:MultiFactorAuthPresent": "false"
                    }
                }
            }
        ]
    }
    ```

6.  **Activity Logging with AWS CloudTrail**
    *   A CloudTrail trail (`CloudSecProjectTrail`) was configured to log all management events across all regions.
    *   Logs were securely stored in the designated S3 bucket.
    *   **Log File Validation** was enabled to ensure the integrity and immutability of the logs for forensic purposes.

## Tools & Services Used

*   **AWS IAM** (Users, Groups, Roles, Policies)
*   **Amazon S3**
*   **Amazon EC2**
*   **AWS CloudTrail**
*   **AWS Billing and Cost Management**

## Key Outcomes

*   **Secured Root Account:** The root user is protected by MFA and is no longer used for daily tasks.
*   **Reduced Attack Surface:** User permissions were drastically limited through least privilege, minimizing the potential impact of a compromised account.
*   **Enhanced Account Protection:** MFA enforcement makes it significantly harder for an attacker to gain access, even with a stolen password.
*   **Scalable Security:** The use of IAM Groups and Roles provides a manageable and scalable framework for permissions.
*   **Complete Audit Trail:** All API calls and user actions are logged, providing full visibility and supporting security investigations and compliance audits.

## Lessons Learned

*   Implementing security concepts hands-on provides a deeper understanding than theory alone.
*   The precision required for writing JSON-based IAM policies is critical; minor errors can lead to unintended permissions.
*   A "deny by default" and least privilege approach is a powerful and effective security posture for any cloud environment.

--

## Author

Dycouzt - Diego Acosta
