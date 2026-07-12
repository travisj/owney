#!/bin/bash
# setup-s3-backup.sh: Setup AWS S3 backup storage with minimal IAM permissions
# Creates: IAM user, S3 bucket, policy, and outputs config

set -e

DOMAIN="${1:?Domain required: $0 <domain>}"
AWS_REGION="${AWS_REGION:-us-east-1}"
BUCKET_NAME="owney-backup-${DOMAIN//./-}"
IAM_USER="owney-backup"

echo "=== AWS S3 Backup Setup for $DOMAIN ==="
echo "Region: $AWS_REGION"
echo "Bucket: $BUCKET_NAME"
echo "IAM User: $IAM_USER"
echo ""

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI not found. Install with: pip install awscli" >&2
    exit 1
fi

# Check credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo "Error: AWS credentials not configured" >&2
    exit 1
fi

echo "Step 1: Creating S3 bucket..."
if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
    echo "  ✓ Bucket already exists: $BUCKET_NAME"
else
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$AWS_REGION" \
        $([ "$AWS_REGION" != "us-east-1" ] && echo "--create-bucket-configuration LocationConstraint=$AWS_REGION")
    echo "  ✓ Created bucket: $BUCKET_NAME"
fi

echo ""
echo "Step 2: Enabling versioning..."
aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled
echo "  ✓ Versioning enabled"

echo ""
echo "Step 3: Enabling encryption..."
aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }
        ]
    }'
echo "  ✓ Server-side encryption enabled (AES256)"

echo ""
echo "Step 4: Blocking public access..."
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
echo "  ✓ Public access blocked"

echo ""
echo "Step 5: Creating IAM user..."
if aws iam get-user --user-name "$IAM_USER" 2>/dev/null; then
    echo "  ✓ User already exists: $IAM_USER"
else
    aws iam create-user --user-name "$IAM_USER"
    echo "  ✓ Created IAM user: $IAM_USER"
fi

echo ""
echo "Step 6: Attaching minimal S3 policy..."
POLICY_DOCUMENT=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::$BUCKET_NAME",
                "arn:aws:s3:::$BUCKET_NAME/*"
            ]
        }
    ]
}
EOF
)

aws iam put-user-policy \
    --user-name "$IAM_USER" \
    --policy-name "S3BackupPolicy" \
    --policy-document "$POLICY_DOCUMENT"
echo "  ✓ Attached policy to $IAM_USER (S3 only, bucket $BUCKET_NAME only)"

echo ""
echo "Step 7: Creating access key..."
KEYS=$(aws iam create-access-key --user-name "$IAM_USER" 2>/dev/null || echo "")
if [ -z "$KEYS" ]; then
    echo "  ⚠ Could not create new key (user may already have max keys)"
    echo "    List existing keys with: aws iam list-access-keys --user-name $IAM_USER"
    echo "    Delete old key with:     aws iam delete-access-key --user-name $IAM_USER --access-key-id <KEY_ID>"
else
    ACCESS_KEY=$(echo "$KEYS" | jq -r '.AccessKey.AccessKeyId')
    SECRET_KEY=$(echo "$KEYS" | jq -r '.AccessKey.SecretAccessKey')
    echo "  ✓ Created access key: $ACCESS_KEY"
fi

echo ""
echo "=========================================="
echo "✓ S3 backup storage ready!"
echo "=========================================="
echo ""
echo "Add to owney.toml [backup] section:"
echo ""
echo "[backup]"
echo "type = \"s3\""
echo "region = \"$AWS_REGION\""
echo "bucket = \"$BUCKET_NAME\""
if [ -n "$KEYS" ]; then
    echo "access_key = \"$ACCESS_KEY\""
    echo "secret_key = \"$SECRET_KEY\""
    echo ""
    echo "⚠ SAVE THESE CREDENTIALS SECURELY (shown only once)"
else
    echo "access_key = \"<from 'aws iam list-access-keys --user-name $IAM_USER'>\" "
    echo "secret_key = \"<from 'aws iam get-access-key-secret --user-name $IAM_USER'>\""
fi
echo ""
echo "Then test with:"
echo "  owneyd --config owney.toml backup create"
echo ""
echo "Backup retention:"
echo "  - Versioning: ON (recover any backup)"
echo "  - Lifecycle: S3 bucket lifecycle rules can transition old backups to Glacier"
echo ""
echo "Cost estimate:"
echo "  - 10 GB/month backup: ~\$0.23 (S3 Standard)"
echo "  - Archive tier (after 30 days): ~\$0.05/month (S3 Glacier)"
echo "  - See: https://aws.amazon.com/s3/pricing/"
