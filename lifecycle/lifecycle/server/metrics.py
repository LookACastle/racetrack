from prometheus_client import Counter

metric_requested_job_deployments = Counter('requested_job_deployments', 'Number of requests to deploy job')
metric_deployed_job = Counter('deployed_job', 'Number of Job deployed successfully')
