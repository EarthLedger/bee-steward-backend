CREATE TABLE users (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  password VARCHAR(122) NOT NULL,
  role VARCHAR(16) NOT NULL,
  created_by VARCHAR(36) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_by VARCHAR(36) NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE (username)
);

insert into users (id, username, password, role, created_by, updated_by) values 
('00000000-0000-0000-0000-000000000000', 'admin', '123', 'admin', '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000');