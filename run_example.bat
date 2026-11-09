@echo off
REM Starts the dashboard on the EXAMPLE plant: chlorine gas + a fluoride feed (config\examples\gas-fluoride).
REM Your normal demo plant is unchanged: run.bat still starts that one.
cd /d %~dp0
set AEGIS_TAGS=config\examples\gas-fluoride\tags.json
set AEGIS_POLICY=config\examples\gas-fluoride\policy.json
set AEGIS_PROCESS=config\examples\gas-fluoride\process.json
call run.bat
