// Retain the old entrypoint so existing direct-build callers stop safely.
throw Error('Central deployment is required. Build and package the reviewed artifact, then use workflow_depot authorization and delivery_control execution. This component does not deploy Workers or apply database migrations directly.');
