import os
from aws_cdk import (
    Duration,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_logs as logs,
    aws_s3 as s3,
)
from constructs import Construct


class LambdaPromtailFunction(Construct):
    def __init__(self, scope, construct_id, config, role, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        
        self.config = config
        self.role = role
        
        env = self._build_env()
        
        # create log group first so we control retention
        function_name = config.get("name", "lambda_promtail")
        log_group = logs.LogGroup(
            self, "Logs",
            log_group_name=f"/aws/lambda/{function_name}",
            retention=self._retention_days(config.get("log_retention_days", 14))
        )
        
        # deploy method
        method = config.get("deployment_method", "asset")
        
        if method == "image":
            self.function = self._create_from_image(env)
        elif method == "s3":
            self.function = self._create_from_s3(env)
        else:
            self.function = self._create_from_asset(env)
        
        self.function.node.add_dependency(log_group)
    
    def _create_from_asset(self, env):
        # check for pre-built binary
        bootstrap = os.path.join(os.path.dirname(__file__), "..", "bootstrap")
        
        if os.path.exists(bootstrap):
            code = lambda_.Code.from_asset(".", exclude=["*", "!bootstrap"])
        else:
            # build from source with docker
            source_path = os.path.join(os.path.dirname(__file__), "..", "..")
            code = lambda_.Code.from_asset(
                source_path,
                bundling=lambda_.BundlingOptions(
                    image=lambda_.Runtime.GO_1_X.bundling_image,
                    command=[
                        "bash", "-c",
                        "cd /asset-input/pkg && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-trimpath go build -mod=readonly -o /asset-output/bootstrap -ldflags='-s -w'"
                    ],
                ),
            )
        
        func = lambda_.Function(
            self, "Fn",
            function_name=self.config.get("name", "lambda_promtail"),
            runtime=lambda_.Runtime.PROVIDED_AL2023,
            code=code,
            handler="bootstrap",
            role=self.role,
            environment=env,
            timeout=Duration.seconds(self.config.get("lambda_timeout", 60)),
            memory_size=self.config.get("lambda_memory", 128),
            reserved_concurrent_executions=self.config.get("reserved_concurrent_executions"),
        )
        
        # vpc config if needed
        if subnets := self.config.get("lambda_vpc_subnets"):
            cfn_func = func.node.default_child
            cfn_func.vpc_config = lambda_.CfnFunction.VpcConfigProperty(
                subnet_ids=subnets,
                security_group_ids=self.config.get("lambda_vpc_security_groups", [])
            )
        
        return func
    
    def _create_from_s3(self, env):
        bucket = self.config.get("lambda_promtail_binary_bucket")
        key = self.config.get("lambda_promtail_binary_key", "lambda-promtail.zip")
        
        if not bucket:
            raise ValueError("lambda_promtail_binary_bucket required when deployment_method is s3")
        
        func = lambda_.Function(
            self, "Fn",
            function_name=self.config.get("name", "lambda_promtail"),
            runtime=lambda_.Runtime.PROVIDED_AL2023,
            code=lambda_.Code.from_bucket(
                bucket=s3.Bucket.from_bucket_name(self, "S3Bucket", bucket),
                key=key
            ),
            handler="bootstrap",
            role=self.role,
            environment=env,
            timeout=Duration.seconds(self.config.get("lambda_timeout", 60)),
            memory_size=self.config.get("lambda_memory", 128),
        )
        
        if subnets := self.config.get("lambda_vpc_subnets"):
            cfn_func = func.node.default_child
            cfn_func.vpc_config = lambda_.CfnFunction.VpcConfigProperty(
                subnet_ids=subnets,
                security_group_ids=self.config.get("lambda_vpc_security_groups", [])
            )
        
        return func
    
    def _create_from_image(self, env):
        image_uri = self.config.get("lambda_promtail_image")
        
        if not image_uri:
            raise ValueError("lambda_promtail_image required when deployment_method is image")
        
        # parse ECR image URI
        if ":" in image_uri:
            repo_name = image_uri.split("/")[-1].split(":")[0]
            tag = image_uri.split(":")[-1]
        else:
            repo_name = image_uri.split("/")[-1]
            tag = "latest"
        
        from aws_cdk import aws_ecr as ecr
        repo = ecr.Repository.from_repository_name(self, "Repo", repo_name)
        
        func = lambda_.DockerImageFunction(
            self, "Fn",
            function_name=self.config.get("name", "lambda_promtail"),
            code=lambda_.DockerImageCode.from_ecr(repo, tag=tag),
            role=self.role,
            environment=env,
            timeout=Duration.seconds(self.config.get("lambda_timeout", 60)),
            memory_size=self.config.get("lambda_memory", 128),
        )
        
        # Add VPC config if provided
        if subnets := self.config.get("lambda_vpc_subnets"):
            cfn_func = func.node.default_child
            cfn_func.vpc_config = lambda_.CfnFunction.VpcConfigProperty(
                subnet_ids=subnets,
                security_group_ids=self.config.get("lambda_vpc_security_groups", [])
            )
        
        return func
    
    def _build_env(self):
        c = self.config
        env = {"WRITE_ADDRESS": c.get("write_address", "")}
        
        # auth
        if username := c.get("username"):
            env["USERNAME"] = username
        if password := c.get("password"):
            env["PASSWORD"] = password
        if token := c.get("bearer_token"):
            env["BEARER_TOKEN"] = token
        
        # optional stuff
        opts = {
            "TENANT_ID": "tenant_id",
            "KEEP_STREAM": "keep_stream",
            "BATCH_SIZE": "batch_size",
            "EXTRA_LABELS": "extra_labels",
            "DROP_LABELS": "drop_labels",
            "RELABEL_CONFIGS": "relabel_configs",
            "SKIP_TLS_VERIFY": "skip_tls_verify",
            "PRINT_LOG_LINE": "print_log_line",
        }
        
        for env_key, cfg_key in opts.items():
            if val := c.get(cfg_key):
                env[env_key] = str(val)
        
        if c.get("omit_extra_labels_prefix"):
            env["OMIT_EXTRA_LABELS_PREFIX"] = "true"
        
        return env
    
    def _retention_days(self, days):
        mapping = {
            1: logs.RetentionDays.ONE_DAY,
            3: logs.RetentionDays.THREE_DAYS,
            5: logs.RetentionDays.FIVE_DAYS,
            7: logs.RetentionDays.ONE_WEEK,
            14: logs.RetentionDays.TWO_WEEKS,
            30: logs.RetentionDays.ONE_MONTH,
            60: logs.RetentionDays.TWO_MONTHS,
            90: logs.RetentionDays.THREE_MONTHS,
            120: logs.RetentionDays.FOUR_MONTHS,
            150: logs.RetentionDays.FIVE_MONTHS,
            180: logs.RetentionDays.SIX_MONTHS,
            365: logs.RetentionDays.ONE_YEAR,
            400: logs.RetentionDays.THIRTEEN_MONTHS,
            545: logs.RetentionDays.EIGHTEEN_MONTHS,
            731: logs.RetentionDays.TWO_YEARS,
            1827: logs.RetentionDays.FIVE_YEARS,
            3653: logs.RetentionDays.TEN_YEARS,
        }
        return mapping.get(days, logs.RetentionDays.TWO_WEEKS)
