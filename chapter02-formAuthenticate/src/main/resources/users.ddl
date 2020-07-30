-- spring-security-core-4.2.4.RELEASE.jar!\org\springframework\security\core\userdetails\jdbc\users.ddl
-- 默认数据库模型 hqldb , varchar_ignorecase 转为  varchar

create table users
(
    username varchar(50) not null primary key,
    password varchar(500) not null,
    enabled boolean not null
);
create table authorities
(
    username varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);
create unique index ix_auth_username on authorities (username, authority);