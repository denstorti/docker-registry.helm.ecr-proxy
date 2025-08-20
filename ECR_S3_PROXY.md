
# Overview

- Uses Service NodePort to expose the registry to nodes.
- Uses S3 bucket to store images and return pre-signed URLs, avoiding the data to go through the registry pods, which can incur cross-AZ traffic costs in AWS.
- Uses ECR as upstream registry for the proxy.
- ECR authentication is done only with auth token with expiration of 12 hours, and the solution is running sidecar pods to refresh the token every 8 hours, and an init container to fetch the token when the registry is started.

# Create ECR repository

`aws ecr create-repository --repository-name nginx --region us-east-1`

# Create S3 bucket

1. Create bucket:
```
AWS_BUCKET_NAME=registry-denisstorti
aws s3api create-bucket --bucket $AWS_BUCKET_NAME --region us-east-1
```

2. Set bucket policy to allow the registry to read and write to the bucket. Replace `<AWS_ACCOUNT_ID>` with the AWS account ID.

**For IAM User Access:**
```bash
AWS_ACCOUNT_ID=281387974444
aws s3api put-bucket-policy --bucket $AWS_BUCKET_NAME --policy '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::'$AWS_ACCOUNT_ID':root"
            },
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:ListBucketMultipartUploads",
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::'$AWS_BUCKET_NAME'",
                "arn:aws:s3:::'$AWS_BUCKET_NAME'/*"
            ]
        }
    ]
}'
```

**For IRSA Role Access (Recommended):**
```bash
AWS_ACCOUNT_ID=281387974444
aws s3api put-bucket-policy --bucket $AWS_BUCKET_NAME --policy '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::'$AWS_ACCOUNT_ID':role/DockerRegistryS3Role"
            },
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:ListBucketMultipartUploads"
            ],
            "Resource": "arn:aws:s3:::'$AWS_BUCKET_NAME'"
        },
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::'$AWS_ACCOUNT_ID':role/DockerRegistryS3Role"
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts"
            ],
            "Resource": "arn:aws:s3:::'$AWS_BUCKET_NAME'/*"
        }
    ]
}'
```


# Create secret for S3 credentials

Create AWS user to access the S3 bucket with bucket permissions and create access key.

Create K8s secret with the access key and secret key:
```
NAMESPACE=docker-registry-proxy-cache
kubectl create secret -n $NAMESPACE generic s3-credentials --from-literal=s3AccessKey=XXX --from-literal=s3SecretKey=XXX
```

Set `s3.bucket` to `$AWS_BUCKET_NAME` in the values files.


# Create secret for ECR credentials

Temporary creds with auth token:

```
AWS_ACCOUNT_ID=281387974444
NAMESPACE=docker-registry-proxy-cache

PASSWORD=$(aws ecr get-login-password --region us-east-1)

kubectl create secret -n $NAMESPACE generic ecr-regcred --from-literal=proxyUsername=AWS --from-literal=proxyPassword=$PASSWORD
```

Set `proxy.secretRef` to `ecr-regcred` in the values files.

# Install Helm chart

```
NAMESPACE=docker-registry-proxy-cache
helm install docker-registry . --namespace $NAMESPACE --create-namespace --values values-s3-ecr-proxy.yaml
```

# Troubleshooting

## S3 Access Denied Error

If you encounter this error:
```
panic: s3aws: AccessDenied: User: arn:aws:sts::281387974444:assumed-role/eksctl-eks-docker-registry-proxy-c-NodeInstanceRole-gdmFm87KxHTG/i-0c8397d78465865e2 is not authorized to perform: s3:ListBucket on resource: "arn:aws:s3:::registry-denisstorti" because no identity-based policy allows the s3:ListBucket action
status code: 403, request id: EGF2W2JK25V8RX8A, host id: ZvAalbIGtttz9LqTpmgtbjNRZrEJiZ3OOAxxPeSAdTWw2DP7eV5X9ib1hOP+uoZeE9nTmLx3Pzc=
```

**Root Cause**: The registry is not using the S3 credentials from the Kubernetes secret and is falling back to the EKS node instance role.

### Solution 1: Fix S3 Credentials Configuration

1. **Verify the secret exists and has correct keys**:
```bash
NAMESPACE=docker-registry-proxy-cache
kubectl get secret -n $NAMESPACE s3-credentials -o yaml
```

2. **Check the secret has the correct keys** (`s3AccessKey` and `s3SecretKey`):
```bash
kubectl get secret -n $NAMESPACE s3-credentials -o jsonpath='{.data}' | jq 'keys'
```

3. **Update the values file to properly reference the secret**:
In `values-s3-ecr-proxy.yaml`, ensure:
```yaml
secrets:
  s3:
    secretRef: "s3-credentials"  # Reference to the secret name
    accessKey: ""               # Leave empty when using secretRef
    secretKey: ""               # Leave empty when using secretRef
```

### Solution 2: Use IAM Roles for Service Accounts (IRSA) - Recommended

Instead of using IAM user credentials, use IRSA for better security:

1. **Create an IAM policy for S3 access**:
```bash
AWS_ACCOUNT_ID=281387974444
AWS_BUCKET_NAME=registry-denisstorti

cat > s3-registry-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:ListBucketMultipartUploads"
            ],
            "Resource": "arn:aws:s3:::${AWS_BUCKET_NAME}"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts"
            ],
            "Resource": "arn:aws:s3:::${AWS_BUCKET_NAME}/*"
        }
    ]
}
EOF

aws iam create-policy \
    --policy-name DockerRegistryS3Policy \
    --policy-document file://s3-registry-policy.json
```

Output: `arn:aws:iam::$AWS_ACCOUNT_ID:policy/DockerRegistryS3Policy`

2. **Create IAM role for service account**:
```bash
CLUSTER_NAME=eks-docker-registry-proxy-cache
NAMESPACE=docker-registry-proxy-cache
SERVICE_ACCOUNT_NAME=docker-registry-sa

# Get OIDC issuer URL
OIDC_ISSUER=$(aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text)

# Create trust policy
cat > trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_ISSUER#https://}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${OIDC_ISSUER#https://}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT_NAME}",
                    "${OIDC_ISSUER#https://}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
EOF

# Create IAM role
aws iam create-role \
    --role-name DockerRegistryS3Role \
    --assume-role-policy-document file://trust-policy.json

# Attach policy to role
aws iam attach-role-policy \
    --role-name DockerRegistryS3Role \
    --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/DockerRegistryS3Policy
```

Output: `arn:aws:iam::$AWS_ACCOUNT_ID:role/DockerRegistryS3Role`

3. **Update values file to use service account**:
Replace `<AWS_ACCOUNT_ID>` with the AWS account ID.
```yaml
serviceAccount:
  create: true
  name: "docker-registry-sa"
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::<AWS_ACCOUNT_ID>:role/DockerRegistryS3Role"

# Remove S3 credentials when using IRSA
secrets:
  s3:
    secretRef: ""
    accessKey: ""
    secretKey: ""
```

## IRSA Troubleshooting

If you encounter this error when using IRSA:
```
panic: s3aws: WebIdentityErr: failed to retrieve credentials
    caused by: SerializationError: failed to unmarshal error message
        status code: 405, request id:
    caused by: UnmarshalError: failed to unmarshal error message
```

This indicates a "MethodNotAllowed" error from STS. Follow these steps to diagnose:

### 1. Verify OIDC Provider Exists

Check if your EKS cluster has an OIDC provider:
```bash
CLUSTER_NAME=eks-docker-registry-proxy-cache
aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text
```

If no OIDC issuer is returned, create one:
```bash
eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve
```

### 2. Verify OIDC Provider in IAM

List OIDC providers and check if your cluster's provider exists:
```bash
aws iam list-open-id-connect-providers
```

The output should include your cluster's OIDC issuer URL.

### 3. Check Service Account and Pod

Verify the service account is created with correct annotations:
```bash
NAMESPACE=docker-registry-proxy-cache
kubectl get serviceaccount -n $NAMESPACE docker-registry-sa -o yaml
```

Check if the pod is using the service account:
```bash
kubectl get pods -n $NAMESPACE -o yaml | grep -A5 -B5 serviceAccount
```

### 4. Verify IAM Role Trust Policy

Check the trust policy of your IAM role:
```bash
aws iam get-role --role-name DockerRegistryS3Role --query 'Role.AssumeRolePolicyDocument'
```

The trust policy should match your cluster's OIDC issuer and namespace/service account.

### 5. Test IRSA from Pod

Create a test pod to verify IRSA is working:
```bash
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: irsa-test
  namespace: $NAMESPACE
spec:
  serviceAccountName: docker-registry-sa
  containers:
  - name: aws-cli
    image: amazon/aws-cli:latest
    command: ['sleep', '3600']
  restartPolicy: Never
EOF

# Test AWS credentials
kubectl exec -n $NAMESPACE irsa-test -- aws sts get-caller-identity
kubectl exec -n $NAMESPACE irsa-test -- aws s3 ls s3://registry-denisstorti/
```

### 6. Common Fixes

**Fix 1: Recreate IAM Role with Correct Trust Policy**
```bash
# Delete existing role
aws iam detach-role-policy --role-name DockerRegistryS3Role --policy-arn arn:aws:iam::281387974444:policy/DockerRegistryS3Policy
aws iam delete-role --role-name DockerRegistryS3Role

# Get correct OIDC issuer (without https://)
OIDC_ISSUER=$(aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text | sed 's|https://||')

# Recreate trust policy with correct issuer
cat > trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::281387974444:oidc-provider/\$OIDC_ISSUER"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "\$OIDC_ISSUER:sub": "system:serviceaccount:docker-registry-proxy-cache:docker-registry-sa",
                    "\$OIDC_ISSUER:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
EOF

# Recreate role
aws iam create-role --role-name DockerRegistryS3Role --assume-role-policy-document file://trust-policy.json
aws iam attach-role-policy --role-name DockerRegistryS3Role --policy-arn arn:aws:iam::281387974444:policy/DockerRegistryS3Policy
```

**Fix 2: Use eksctl for IRSA (Recommended)**
```bash
# Delete existing service account
kubectl delete serviceaccount -n docker-registry-proxy-cache docker-registry-sa

# Create service account with IRSA using eksctl
eksctl create iamserviceaccount \
    --cluster=$CLUSTER_NAME \
    --namespace=docker-registry-proxy-cache \
    --name=docker-registry-sa \
    --attach-policy-arn=arn:aws:iam::281387974444:policy/DockerRegistryS3Policy \
    --override-existing-serviceaccounts \
    --approve
```
