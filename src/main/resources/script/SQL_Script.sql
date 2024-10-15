CREATE DATABASE login;

USE login;

-- Creating 'user' table
CREATE TABLE user (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(255) UNIQUE NOT NULL,
    user_password VARCHAR(255) NOT NULL
);

-- Creating 'role' table
CREATE TABLE role (
    role_id BIGINT AUTO_INCREMENT UNIQUE PRIMARY KEY,
    role_authority VARCHAR(255) NOT NULL
);

-- Creating the join table 'user_role_jun'
CREATE TABLE user_role_jun (
    user_id INT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES user(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE
);

SELECT * FROM user;
SELECT * FROM role;
SELECT * FROM user_role_jun;

DROP TABLE user;
DROP TABLE role;
DROP TABLE user_role_jun;