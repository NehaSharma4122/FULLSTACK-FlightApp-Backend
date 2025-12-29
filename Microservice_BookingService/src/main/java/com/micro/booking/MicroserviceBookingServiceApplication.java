package com.micro.booking;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

@SpringBootApplication
@EnableFeignClients(basePackages = "com.micro.booking")
public class MicroserviceBookingServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(MicroserviceBookingServiceApplication.class, args);
	}
	
	@Bean
    CommandLineRunner mongoDatabaseInfo(Environment env) {
        return args -> {

            String uri = env.getProperty("spring.data.mongodb.uri");
            String database = env.getProperty("spring.data.mongodb.database");

            System.out.println("====================================");
            System.out.println(" DATABASE TYPE : MongoDB (Reactive)");
            System.out.println(" MONGO URI    : " + uri);
            System.out.println(" DATABASE     : " + database);
            System.out.println("====================================");
        };
    }

}
