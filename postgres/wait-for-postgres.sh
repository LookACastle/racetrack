#!/bin/bash

until pg_isready -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER -d $POSTGRES_DB; do
    echo "Waiting for ${POSTGRES_HOST}:${POSTGRES_PORT}";
    sleep 1;
done;
echo "PostgreSQL ready ✓"
