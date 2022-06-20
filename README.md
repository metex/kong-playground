## Backup kong postgres database
docker exec -it --user postgres kong-database pg_dump -U kong -F c kong > kong.tar
docker exec -it --user postgres kong-database pg_dumpall -U kong > all_pg_dbs.sql

## Restore
docker exec --user postgres kong-database pg_restore -U kong -Ft -d kong < kong.tar

## Kong CLI commands
docker run --rm -e "KONG_DATABASE=postgres" -e "KONG_PG_HOST=kong-database" -e "KONG_PG_PASSWORD=kong" -e "KONG_PASSWORD=kong" custom-kong kong migrations bootstrap