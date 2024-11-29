# RBAC API (Role-Based Access Control)
This project implements an API with role-based access control (RBAC) for managing user authentication, authorization, and role-based access using Node.js, Express, and Microsoft SQL Server.

## Table of Contents:
### Features
### Prerequisites
### Setup & Installation
### Environment Configuration
### Running the Application
### API Endpoints
### Security Measures
### Swagger API Documentation
### Dependencies

## Features:
- User registration with a default role (User).
- Admin-controlled role management (only Admin can create Moderator or Admin users).
- JWT-based authentication.
- Middleware for role-based access control.
- Secure configuration using environment variables.
- API documentation using Swagger.
- Security enhancements: CORS, rate limiting, and Helmet for HTTP headers.

## Prerequisites:
Before you begin, ensure you have the following installed:
- Node.js (v14 or higher)
- Microsoft SQL Server
- SQL Server Management System(SSMS)
- NPM (comes with Node.js)

## Setup & Installation:
### Clone the repository:-
#### 1)To clone the repository
-     git clone https://github.com/hemanth0808/RBAC_DEMO.git
#### 2)To navigate to repository folder
-     cd auth_rbac
### Install dependencies:-
-     npm install
### Download and Install SQL Server:-
#### Download SQL Server
- Visit the official Microsoft SQL Server download page: SQL Server Downloads.
- Select the Developer Edition (free for development purposes) or Express Edition (lightweight version).
#### Run the Installer
- Launch the downloaded installer (SQLServer2022-x64-ENU.exe or similar).
- Choose Custom or Basic installation depending on your needs.
- Follow the on-screen instructions and accept the license terms.
#### Installation Configuration
- During the installation, choose: Default Instance (recommended for simplicity).
#### Set the Authentication Mode
- Windows Authentication or Mixed Mode (Windows and SQL Server authentication).
- If choosing Mixed Mode, set a SQL Server Admin password.
#### Complete Installation
- Click Install and wait for the process to complete.
- Once installed, note the instance name (e.g., MSSQLSERVER for the default instance).
### SQL Server Configuration for Connection:-
Ensure the following configurations are set for a smooth connection.
#### Connect with windows authentication and then create a user
- Open SSMS and click conneect.
- There select our default SQL server and connect with windows authentication.
- Then go into logins and create a new user with database connection, database reader, database writer,..etc permissions.
-     username:username
      password:password
#### Enable TCP/IP Protocol
- Open SQL Server Configuration Manager.
- Navigate to SQL Server Network Configuration > Protocols for [Instance Name].
- Ensure TCP/IP is Enabled.
#### Check Firewall Settings
- Ensure that your firewall allows incoming connections on the SQL Server port (default is 1433).
#### Set Authentication Mode
- Right-click on the server in SSMS.
- Go to Properties > Security.
- Ensure SQL Server and Windows Authentication mode is selected.
### Setup your SQL Server database:-
- Create a new database named RBAC.
- Create a Users table with the following schema.
-     CREATE TABLE Users ( \
      UserID INT PRIMARY KEY IDENTITY(1,1), \
      Username NVARCHAR(50) UNIQUE NOT NULL, \
      PasswordHash NVARCHAR(MAX) NOT NULL, \
      Role NVARCHAR(20) NOT NULL
      );
## Environment Configuration:
Create a .env file in the root directory and add the following configuration.
-     JWT_SECRET=your_jwt_secret_key
      PORT=5000
      SERVER=your_server_name
      DB=your_database_name
      USER=your_username
      PASSWORD=your_password
Note: Replace your_jwt_secret_key and database connection values with your actual configuration.
## Running the Application:
### Start the server:-
-      npm start
- Access the server: The server runs on http://localhost:5000.
- API Documentation: Access the Swagger UI at http://localhost:5000/api-docs.
## API Endpoints:
### Authentication Endpoints:-
#### Register
-     curl --location 'http://localhost:5000/register' \
      --header 'Content-Type: application/json' \
      --data '{
      "username": "User",
      "password": "User"
       }'

Register a new user (default role: User). We don't need authorization or authentication to register a user here. It is publicly accessible.
#### Login
-     curl --location 'http://localhost:5000/login' \
      --header 'Content-Type: application/json' \
      --data '{
          "username": "admin",
          "password": "Admin"
      }'

Users log in using their credentials. If the credentials are valid, the system returns a JWT Token in response. This JWT Token should be used in the authorization header of protected routes.
### User Management Endpoints:-
Valid Roles : "User", "Moderator", "Admin".
#### Create User
-     curl --location 'http://localhost:5000/create-user' \
      --header 'Content-Type: application/json' \
      --header 'Authorization: BearerToken generated by the login route' \
      --data '{
          "username": "User",
          "password": "User",
          "role":"Admin"
      }'

Register a new user of any role, here only the admin can create a user of any role(user, moderator, admin).(use Token generated in login route).
#### Users List
-     curl --location 'http://localhost:5000/usersList' \
      --header 'Authorization: BearerToken generated by the login route'

only admins can get a list of all users from the database.(use Token generated in login route).
### Role-Based Endpoints:-
#### Admin
-     curl --location 'http://localhost:5000/admin' \
      --header 'Authorization: BearerToken generated by the login route'

This is a protected route for admins. only admins can view this page.
#### Moderator
-      curl --location 'http://localhost:5000/moderator' \
      --header 'Authorization: BearerToken generated by the login route'

This is a protected route for moderators. both admins and moderators can view this page.
#### User
-      curl --location 'http://localhost:5000/user' \
      --header 'Authorization: BearerToken generated by the login route'

This is a protected route for users. here admins, moderators, and users can view this page.
## Security Measures:
### JWT Authentication:-
#### Description
- JSON Web Tokens (JWT) are used to securely authenticate users. Upon successful login, a JWT is generated and sent to the client. This token is included in subsequent requests to verify the user's identity.
#### Key Points
- Ensures only authenticated users can access protected endpoints.
- Contains user information and has an expiration time.
### Role-Based Access Control (RBAC):-
#### Description
- RBAC restricts access to API endpoints based on user roles (e.g., User, Moderator, Admin). Different roles have different permissions, ensuring that only authorized users can perform specific actions.
#### Key Points
- Enhances security by controlling access based on roles.
- Prevents unauthorized users from accessing sensitive operations.
### Helmet:-
#### Description
- Helmet is a Node.js middleware that enhances security by setting various HTTP headers. It helps protect the app from common vulnerabilities like cross-site scripting (XSS) and clickjacking.
#### Key Points
- Provides security against common web threats.
- Configures headers like Content-Security-Policy, X-Frame-Options, and X-XSS-Protection.
### CORS (Cross-Origin Resource Sharing):-
#### Description
- CORS controls which domains can access your API, preventing unauthorized cross-origin requests. It is essential for securely exposing your API to specific front-end applications.
- CORS doesn't directly block all untrusted origins; instead, it controls which origins are allowed to access your resources. If configured correctly, it ensures that only requests from trusted domains are processed by your API. 
#### Key Points
- Restricts access to trusted origins only.(allows only trusted origins).
- Prevents potential cross-origin attacks by validating request origins.
### Rate Limiting:-
#### Description
- Rate limiting restricts the number of requests a client can make to the API within a specified time frame. This helps protect against abuse, such as brute-force attacks or DDoS attempts.
#### Key Points
- Limits the number of requests per IP address.
- Prevents server overload and enhances overall API stability.
## Swagger API Documentation:
- Swagger provides interactive API documentation.
- Swagger is a powerful framework used to design, document, and interact with APIs. It helps developers understand the functionality of an API and provides an interactive platform to test endpoints.
### Features of Swagger Documentation:-
- API Specification (OpenAPI).
- Interactive UI.
- Endpoint Details.
- Security Schemes.
- Automatic Generation.
### Start the server:-
- Navigate to http://localhost:5000/api-docs in your browser.
## Dependencies:
- express: Web framework for Node.js.
- jsonwebtoken: JWT for authentication.
- bcryptjs: Hashing passwords.
- dotenv: Manage environment variables.
- mssql: Microsoft SQL Server client.
- helmet: Security middleware.
- cors: Handle Cross-Origin Resource Sharing.
- express-rate-limit: Rate limiting for requests.
- swagger-jsdoc & swagger-ui-express: Generate and serve Swagger API docs.
  
