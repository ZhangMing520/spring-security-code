create table users
(
    id       bigint(20)  not null auto_increment,
    username varchar(50) not null,
    password varchar(60),
    enable   tinyint(4)  not null default '1' comment '用户是否可用',
    roles    text character set utf8 comment '用户橘色，多个用户之间使用逗号隔开',
    primary key (id),
    key username (username)
);


insert into users (username, password, roles)
values ('admin', '123', 'ROLE_ADMIN,ROLE_USER');

insert into users (username, password, roles)
values ('user', '123', 'ROLE_USER');