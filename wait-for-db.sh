#!/bin/sh
set -e

host="$1"
shift

echo "Waiting for Postgres at $host..."

until PGPASSWORD=$DATABASE_PASSWORD psql -h "$host" -U "$DATABASE_USER" -d "$DATABASE_NAME" -c '\q'; do
  echo "Postgres is unavailable - sleeping"
  sleep 2
done

echo "Postgres is up - executing command"
exec "$@"
