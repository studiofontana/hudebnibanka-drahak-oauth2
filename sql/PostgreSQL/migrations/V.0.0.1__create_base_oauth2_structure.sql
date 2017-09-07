-- Application users
CREATE TABLE oauth_user (
  user_id       UUID          PRIMARY KEY,
  username      VARCHAR(50)   NOT NULL,
  password      CHAR(64)      NOT NULL
);

-- OAuth2 clients
CREATE TABLE oauth_client (
	client_id 		UUID		      PRIMARY KEY,
	name          VARCHAR(50)   NOT NULL,
	secret		    CHAR(64)	    NOT NULL,
	redirect_url	VARCHAR(255)	NOT NULL
);

-- OAuth2 scope table
CREATE TABLE oauth_scope (
  name 		      VARCHAR(80) 	PRIMARY KEY,
  description 	VARCHAR(255) 	NOT NULL
);

-- OAuth2 grant types
CREATE TABLE oauth_grant (
  grant_id 		  serial    		PRIMARY KEY,
  name 		      VARCHAR(80) 	NOT NULL,
  description 	VARCHAR(255) 	NOT NULL
);

-- OAuth2 client to grant M:N connection table
CREATE TABLE oauth_client_grant (
  client_grant_id 	serial 	PRIMARY KEY,
  client_id 		    UUID 		NOT NULL,
  grant_id 		      INT 		NOT NULL
);

ALTER TABLE oauth_client_grant
  ADD FOREIGN KEY (grant_id) REFERENCES oauth_grant (grant_id) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD FOREIGN KEY (client_id) REFERENCES oauth_client (client_id) ON DELETE CASCADE ON UPDATE CASCADE;

-- OAuth2 access token table
CREATE TABLE oauth_access_token (
  access_token    CHAR(64)    PRIMARY KEY,
  client_id       UUID        NOT NULL,
  user_id         UUID        NULL,
  expires_at      TIMESTAMP   NOT NULL
);

ALTER TABLE oauth_access_token
  ADD FOREIGN KEY (user_id) REFERENCES oauth_user (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD FOREIGN KEY (client_id) REFERENCES oauth_client (client_id) ON DELETE CASCADE ON UPDATE CASCADE;

-- OAuth2 authorization code table
CREATE TABLE oauth_authorization_code (
  authorization_code  CHAR(64)    PRIMARY KEY,
  client_id           UUID        NOT NULL,
  user_id             UUID        NOT NULL,
  expires_at          TIMESTAMP   NOT NULL
);

ALTER TABLE oauth_authorization_code
  ADD FOREIGN KEY (user_id) REFERENCES oauth_user (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD FOREIGN KEY (client_id) REFERENCES oauth_client (client_id) ON DELETE CASCADE ON UPDATE CASCADE;

-- OAuth2 refresh token table
CREATE TABLE oauth_refresh_token (
  refresh_token       CHAR(64)    PRIMARY KEY,
  client_id           UUID        NOT NULL,
  user_id             UUID        NULL,
  expires_at          TIMESTAMP   NOT NULL
);

ALTER TABLE oauth_refresh_token
  ADD FOREIGN KEY (user_id) REFERENCES oauth_user (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD FOREIGN KEY (client_id) REFERENCES oauth_client (client_id) ON DELETE CASCADE ON UPDATE CASCADE;

-- OAuth2 scope to authorization code connection table
CREATE TABLE oauth_authorization_code_scope (
  authorization_code_scope_id   SERIAL      PRIMARY KEY,
  authorization_code            CHAR(64)    NOT NULL,
  scope_name                    VARCHAR(80) NOT NULL
);

ALTER TABLE oauth_authorization_code_scope
  ADD FOREIGN KEY (authorization_code) REFERENCES oauth_authorization_code (authorization_code) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD FOREIGN KEY (scope_name) REFERENCES oauth_scope (name) ON DELETE CASCADE ON UPDATE CASCADE;

-- OAuth2 scope to access_token connection table
CREATE TABLE oauth_access_token_scope (
  access_token_scope_id         SERIAL      PRIMARY KEY,
  access_token                  CHAR(64)    NOT NULL,
  scope_name                    VARCHAR(80) NOT NULL
);

ALTER TABLE oauth_access_token_scope
  ADD FOREIGN KEY (access_token) REFERENCES oauth_access_token (access_token) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD FOREIGN KEY (scope_name) REFERENCES oauth_scope (name) ON DELETE CASCADE ON UPDATE CASCADE;
