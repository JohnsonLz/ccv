drop database if exists ccv;

create database ccv;

use ccv;

create table User (
userId int auto_increment,
userName varchar(16) not null unique,
password varchar(16) not null,
email varchar(32),
primary key(userId)
);

create table Project (
projectId int auto_increment,
projectName varchar(16) not null unique,
primary key(projectId)
);

create table Contributer (
contributerId int auto_increment,
userId int,
projectId int,
primary key(contributerId),
foreign key(userId) references User(userId),
foreign key(projectId) references Project(projectId)
);

insert into User (userName, password, email) values('lz', '283447', '821051701@qq.com');
insert into User (userName, password) values('chelease', '123456');
insert into Project(projectName) values('ccv');
