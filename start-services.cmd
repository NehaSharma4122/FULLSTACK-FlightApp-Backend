@echo off
echo Starting Eureka Server on Port 9997...
start "Eureka Server" cmd /k ^
java -jar Microservices_EurekaServer\target\Microservices_EurekaServer-0.0.1-SNAPSHOT.jar --server.port=9997 --eureka.client.register-with-eureka=false --eureka.client.fetch-registry=false

timeout /t 15

echo Starting Flight Service...
start "Flight Service" cmd /k ^
java -jar Microservice_FlightService\target\Microservice_FlightService-0.0.1-SNAPSHOT.jar --server.port=9999 --eureka.client.service-url.defaultZone=http://localhost:9997/eureka/

timeout /t 10

echo Starting Booking Service...
start "Booking Service" cmd /k ^
java -jar Microservice_BookingService\target\Microservice_BookingService-0.0.1-SNAPSHOT.jar --server.port=9998 --eureka.client.service-url.defaultZone=http://localhost:9997/eureka/

timeout /t 10

echo Starting API Gateway...
start "API Gateway" cmd /k ^
java -jar Microservices_APIGateway\target\Microservices_APIGateway-0.0.1-SNAPSHOT.jar --eureka.client.service-url.defaultZone=http://localhost:9997/eureka/

echo ===============================
echo All services started with Port Overrides
echo ===============================
this is the content