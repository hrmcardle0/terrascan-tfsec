# Use the tfsec base image
FROM aquasec/tfsec

# Copy your Terraform file into the container
WORKDIR /scripts
COPY entrypoint.sh /scripts/entrypoint.sh
#VOLUME ["/terraform"]

# Set the entrypoint to run tfsec with your Terraform file

# Command to sleep indefinitely
ENTRYPOINT ["sh", "/scripts/entrypoint.sh"]