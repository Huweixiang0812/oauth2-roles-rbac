# OAuth2 Roles-Based Access Control (RBAC)

This project, `oauth2-roles-rbac`, demonstrates how to implement OAuth2-based Role-Based Access Control (RBAC) using Java 8, MySQL 8, Docker, and Maven. It utilizes Spring Security, MyBatis-Plus, MySQL JDBC Driver, and Lombok for building a secure and role-aware authorization system.

## Prerequisites

Before you can start using this project, make sure you have the following prerequisites installed:

1. **Java 8**: Ensure you have Java 8 installed on your system.

2. **MySQL 8**: Install MySQL 8 and ensure it's running.

3. **Docker**: Docker is required to run the application containers.

4. **Maven**: This project uses Maven for dependency management. Install it if you haven't already.

## Setup

Follow these steps to set up and run the project:

1. **Database Setup**:

    - Create a MySQL 8 database.
    - Import the provided database script from the project directory. This script includes tables for roles, URL resources, and role-to-URL mappings.
    - Map the database running on port 3306 in Docker to your localhost.

2. **Authentication and Authorization Flow**:

   The project implements an OAuth2-based RBAC system. Here's how it works:

    - When a user attempts to access a protected resource at `http://client:8082/product`, the client checks if the user is authenticated.
    - If the user is not authenticated, they are redirected to `http://auth-server:8080/oauth2/authorize` to obtain authorization.
    - After successful authentication on the authorization server, an authorization code is provided.
    - The user is then redirected back to `http://client:8082/login/oauth2/code/demo` with the authorization code.
    - The client uses this code to request an access token from the authorization server at `http://auth-server:8080/oauth2/token`.
    - With the access token in hand, the client can securely request the protected resource at `http://client:8082/product` from the resource server.
    - The resource server evaluates the user's role and permissions to ensure authorized access to the requested resource, providing secure and role-based access control.


## License

This project is licensed under the [MIT License](LICENSE).

---

Feel free to contribute to this project, report issues, or provide feedback. Implementing RBAC with OAuth2 adds a layer of security to your applications, ensuring that users only access resources they are authorized to use.