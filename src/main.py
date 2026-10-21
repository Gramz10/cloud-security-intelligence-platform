from src.utils import get_platform_status, format_resource_name

def main():
    status = get_platform_status()
    print(status)

    resource_name = format_resource_name("aws-server-01")
    print(resource_name)


if __name__ == "__main__":
    main()