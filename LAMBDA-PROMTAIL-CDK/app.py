#!/usr/bin/env python3
import aws_cdk as cdk
from stacks.lambda_promtail_stack import LambdaPromtailStack

app = cdk.App()

config = app.node.try_get_context("lambda_promtail") or {}

LambdaPromtailStack(
    app,
    "LambdaPromtailStack",
    config=config,
    description="Lambda Promtail - forwards AWS logs to Loki",
    env=cdk.Environment(
        account=config.get("account"),
        region=config.get("region")
    )
)

app.synth()
