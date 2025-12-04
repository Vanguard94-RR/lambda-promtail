from aws_cdk import (
    Stack,
    Duration,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_logs as logs,
    aws_s3 as s3,
    aws_kinesis as kinesis,
    aws_sqs as sqs,
    aws_logs_destinations as logs_destinations,
    aws_s3_notifications as s3n,
)
from aws_cdk.aws_lambda_event_sources import KinesisEventSource, SqsEventSource
from constructs import Construct
from lib.lambda_function import LambdaPromtailFunction


class LambdaPromtailStack(Stack):
    def __init__(self, scope, construct_id, config, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        
        self.config = config
        
        # basic validation
        if not config.get("write_address"):
            raise ValueError("write_address is required")
        
        # check auth setup
        has_basic = config.get("username") and config.get("password")
        has_token = config.get("bearer_token")
        if has_basic and has_token:
            raise ValueError("use either basic auth or bearer token, not both")
        
        # create IAM role
        self.role = iam.Role(
            self, "Role",
            role_name=config.get("name", "lambda_promtail"),
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        
        # add cloudwatch logs permissions if not in VPC
        if not config.get("lambda_vpc_subnets"):
            self.role.add_to_policy(iam.PolicyStatement(
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/{config.get('name', 'lambda_promtail')}:*"]
            ))
        
        # create lambda function
        self.function = LambdaPromtailFunction(
            self, "Function",
            config=config,
            role=self.role
        )
        
        # configure retries
        lambda_.EventInvokeConfig(
            self, "InvokeConfig",
            function=self.function.function,
            max_event_age=Duration.hours(6),
            retry_attempts=2,
        )
        
        # add IAM permissions for data sources
        self._add_permissions()
        
        # wire up event sources
        self._setup_event_sources()
    
    def _add_permissions(self):
        # S3 buckets
        buckets = self.config.get("bucket_names", [])
        if buckets:
            self.role.add_to_policy(iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{b}/*" for b in buckets]
            ))
        
        # Kinesis streams
        streams = self.config.get("kinesis_stream_names", [])
        if streams:
            self.role.add_to_policy(iam.PolicyStatement(
                actions=["kinesis:DescribeStream", "kinesis:GetRecords", 
                        "kinesis:GetShardIterator", "kinesis:ListShards", "kinesis:ListStreams"],
                resources=[f"arn:aws:kinesis:{self.region}:{self.account}:stream/{s}" for s in streams]
            ))
        
        # KMS key
        if kms_key := self.config.get("kms_key_arn"):
            self.role.add_to_policy(iam.PolicyStatement(
                actions=["kms:Decrypt"],
                resources=[kms_key]
            ))
        
        # Secrets Manager
        secret_arns = [
            self.config.get("username_secret_arn"),
            self.config.get("password_secret_arn"),
            self.config.get("bearer_token_secret_arn")
        ]
        secret_arns = [a for a in secret_arns if a]
        if secret_arns:
            self.role.add_to_policy(iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=secret_arns
            ))
        
        # SSM parameters
        param_arns = [
            self.config.get("username_parameter_arn"),
            self.config.get("password_parameter_arn"),
            self.config.get("bearer_token_parameter_arn")
        ]
        param_arns = [a for a in param_arns if a]
        if param_arns:
            self.role.add_to_policy(iam.PolicyStatement(
                actions=["ssm:GetParameter"],
                resources=param_arns
            ))
        
        # VPC execution role
        if self.config.get("lambda_vpc_subnets"):
            self.role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            )
        
        # SQS queues
        if self.config.get("sqs_enabled"):
            queue_prefix = self.config.get("sqs_queue_name_prefix", "s3-to-lambda-promtail")
            self.role.add_to_policy(iam.PolicyStatement(
                actions=["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                resources=[f"arn:aws:sqs:{self.region}:{self.account}:{queue_prefix}*"]
            ))
    
    def _setup_event_sources(self):
        # CloudWatch Logs
        for log_group in self.config.get("log_group_names", []):
            lg = logs.LogGroup.from_log_group_name(
                self, f"LogGroup{self._clean_id(log_group)}", log_group
            )
            logs.SubscriptionFilter(
                self, f"Filter{self._clean_id(log_group)}",
                log_group=lg,
                destination=logs_destinations.LambdaDestination(self.function.function),
                filter_pattern=logs.FilterPattern.all_events()
            )
        
        # S3 buckets (direct or via SQS)
        buckets = self.config.get("bucket_names", [])
        if buckets:
            if self.config.get("sqs_enabled"):
                self._setup_s3_via_sqs(buckets)
            else:
                self._setup_s3_direct(buckets)
        
        # Kinesis streams
        for stream_name in self.config.get("kinesis_stream_names", []):
            stream = kinesis.Stream.from_stream_attributes(
                self, f"Stream{self._clean_id(stream_name)}",
                stream_arn=f"arn:aws:kinesis:{self.region}:{self.account}:stream/{stream_name}"
            )
            self.function.function.add_event_source(
                KinesisEventSource(
                    stream,
                    starting_position=lambda_.StartingPosition.LATEST,
                    batch_size=100,
                    retry_attempts=10
                )
            )
    
    def _setup_s3_direct(self, buckets):
        for bucket_name in buckets:
            bucket = s3.Bucket.from_bucket_name(self, f"Bucket{self._clean_id(bucket_name)}", bucket_name)
            bucket.add_event_notification(
                s3.EventType.OBJECT_CREATED,
                s3n.LambdaDestination(self.function.function),
                s3.NotificationKeyFilter(
                    prefix=self.config.get("filter_prefix", "AWSLogs/"),
                    suffix=self.config.get("filter_suffix", ".gz")
                )
            )
    
    def _setup_s3_via_sqs(self, buckets):
        prefix = self.config.get("sqs_queue_name_prefix", "s3-to-lambda-promtail")
        
        # dead letter queue
        dlq = sqs.Queue(
            self, "DLQ",
            queue_name=f"{prefix}-dlq",
            encryption=sqs.QueueEncryption.SQS_MANAGED
        )
        
        # main queue
        queue = sqs.Queue(
            self, "Queue",
            queue_name=f"{prefix}-main",
            visibility_timeout=Duration.minutes(5),
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            dead_letter_queue=sqs.DeadLetterQueue(max_receive_count=5, queue=dlq)
        )
        
        # connect S3 buckets to queue
        for bucket_name in buckets:
            bucket = s3.Bucket.from_bucket_name(self, f"BucketSQS{self._clean_id(bucket_name)}", bucket_name)
            bucket.add_event_notification(
                s3.EventType.OBJECT_CREATED,
                s3n.SqsDestination(queue),
                s3.NotificationKeyFilter(
                    prefix=self.config.get("filter_prefix", "AWSLogs/"),
                    suffix=self.config.get("filter_suffix", ".gz")
                )
            )
        
        # connect queue to lambda
        self.function.function.add_event_source(SqsEventSource(queue, batch_size=10))
    
    def _clean_id(self, name):
        return name.replace("/", "-").replace("_", "-").replace(".", "-").strip("-")
