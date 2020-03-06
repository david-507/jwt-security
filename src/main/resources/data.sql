-- Contraseña: Admin1
insert into users (id, full_name, email, username, password, avatar, created, updated)
values (1, 'Admin admin', 'admin@demo.com','admin','$2a$10$DBJhFdEGTeAqoLLsGfXwYObYXpt/amU0wpsRtKQtwJdC5n.MOXgxC','https://api.adorable.io/avatars/285/admin@demo.com.png',CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

insert into user_entity_roles (user_entity_id, roles) values (1,'USER');
insert into user_entity_roles (user_entity_id, roles) values (1,'ADMIN');