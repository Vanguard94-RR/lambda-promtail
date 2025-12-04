# Lambda Promtail CDK

Deploy lambda-promtail to forward AWS logs to Loki.

## Deploy

```bash
pip install -r requirements.txt
cdk deploy
```

CDK builds the Go binary automatically.

## Configure

Edit `cdk.json`:

```json
{
  "context": {
    "lambda_promtail": {
      "write_address": "https://loki.example.com/loki/api/v1/push",
      "username": "admin",
      "password": "secret",
      "log_group_names": ["/aws/lambda/my-function"],
      "bucket_names": ["my-logs-bucket"]
    }
  }
}
```

## Event Sources

- `log_group_names` - CloudWatch Logs
- `bucket_names` - S3 buckets
- `kinesis_stream_name` - Kinesis streams (must exist)
- `sqs_enabled` - Use SQS for S3 (high volume)
