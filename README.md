Crear un contenedor en postgres: 

docker run --name auth-postgres -e POSTGRES_USER=juanma -e POSTGRES_PASSWORD=pass -p 5432:5432 -d postgres

docker run --name auth-postgres -e POSTGRES_USER=juanma -e POSTGRES_PASSWORD=pass -p 5432:5432 -d postgres -c 'shared_preload_libraries=uuid-ossp'
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
