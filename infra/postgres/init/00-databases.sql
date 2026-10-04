-- Runs once, on first start of an empty data volume.
-- `engine` holds the meta (write side) and readmodel (query side) schemas;
-- Lakekeeper keeps its catalog in its own database.
CREATE DATABASE lakekeeper;
\connect engine
CREATE SCHEMA IF NOT EXISTS meta;
CREATE SCHEMA IF NOT EXISTS readmodel;
