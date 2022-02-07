#!/bin/sh

pytest --docker-compose tests/ -sv $@
