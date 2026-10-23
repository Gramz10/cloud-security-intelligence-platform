import logging

from src.utils import get_platform_status, format_resource_name

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(message)s ',
    level=logging.INFO,
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger(__name__)

def main():
    logger.info("Starting Cloud Security Intelligence Platform")

    status = get_platform_status()
    logger.info(status)

    resource_name = format_resource_name("aws-server-01")
    logger.info("Formatted resource name: %s", resource_name)


if __name__ == "__main__":
    main()