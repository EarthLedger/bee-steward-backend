table! {
    nodes (addr) {
        addr -> Varchar,
        server_id -> Varchar,
        server_idx -> Integer,
        customer -> Nullable<Varchar>,
        sub -> Nullable<Varchar>,
        cheque_book_addr -> Nullable<Varchar>,
        run_status -> Integer,
        connection -> Integer,
        depth -> Integer,
        cheque_received_count -> Integer,
        cheque_received_balance -> Varchar,
        peer_max_postive_balance -> Varchar,
        node_bzz -> Varchar,
        node_xdai -> Varchar,
        cheque_bzz -> Varchar,
        created_by -> Varchar,
        created_at -> Timestamp,
        updated_by -> Varchar,
        updated_at -> Timestamp,
    }
}

table! {
    node_infos (addr) {
        addr -> Varchar,
        cheque_book_addr -> Varchar,
        run_status -> Integer,
        connection -> Integer,
        depth -> Integer,
        cheque_received_count -> Integer,
        cheque_received_balance -> Varchar,
        peer_max_postive_balance -> Varchar,
        node_bzz -> Varchar,
        node_xdai -> Varchar,
        cheque_bzz -> Varchar,
        created_by -> Varchar,
        created_at -> Timestamp,
        updated_by -> Varchar,
        updated_at -> Timestamp,
    }
}

table! {
    servers (id) {
        id -> Varchar,
        ip -> Varchar,
        created_by -> Varchar,
        created_at -> Timestamp,
        updated_by -> Varchar,
        updated_at -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Varchar,
        username -> Varchar,
        password -> Varchar,
        role -> Varchar,
        created_by -> Varchar,
        created_at -> Timestamp,
        updated_by -> Varchar,
        updated_at -> Timestamp,
    }
}

allow_tables_to_appear_in_same_query!(
    nodes,
    node_infos,
    servers,
    users,
);
