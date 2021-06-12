table! {
    nodes (addr) {
        addr -> Varchar,
        server_id -> Varchar,
        server_idx -> Integer,
        customer -> Nullable<Varchar>,
        sub -> Nullable<Varchar>,
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
    servers,
    users,
);
