CREATE TABLE node_infos (
  addr VARCHAR(64) NOT NULL PRIMARY KEY,
	cheque_book_addr VARCHAR(64) NOT NULL,
	run_status INT NOT NULL DEFAULT 0,
	connection INT NOT NULL DEFAULT 0,
	depth INT NOT NULL DEFAULT 0,
	cheque_received_count INT NOT NULL DEFAULT 0,
	cheque_received_balance VARCHAR(256) NOT NULL DEFAULT '0',
	peer_max_postive_balance VARCHAR(256) NOT NULL DEFAULT '0',
	node_bzz VARCHAR(256) NOT NULL DEFAULT '0',
	node_xdai VARCHAR(256) NOT NULL DEFAULT '0',
	cheque_bzz VARCHAR(256) NOT NULL DEFAULT '0',
	created_by VARCHAR(36) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_by VARCHAR(36) NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);