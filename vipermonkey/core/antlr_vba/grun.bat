@echo off
set classpath0=%CLASSPATH%
SET CLASSPATH=.;C:\Javalib\antlr-4.6-complete.jar;%CLASSPATH%
java org.antlr.v4.gui.TestRig %*
set classpath=%classpath0%
set classpath0=
