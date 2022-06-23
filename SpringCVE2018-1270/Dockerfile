FROM openjdk:19-ea-26-slim-buster
RUN wget -q https://github.com/nddmars/Security-Collections/raw/master/SpringCVE2018-1270/SpringExploitCVE20181270.jar
RUN java -jar SpringExploitCVE20181270.jar
EXPOSE 8080:8080