package com.txt.security.core.crypto.cipher.main;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class AvailableCiphersMain {

    public static void main(String[] args) {
        System.out.println("1. GetAllCipherAlgorithms");
        whenGetServices_thenGetAllCipherAlgorithms();

        System.out.println("\n2. GetAllCompatibleCipherAlgorithms");
        whenGetServicesWithFilter_thenGetAllCompatibleCipherAlgorithms();
    }

    public static void whenGetServices_thenGetAllCipherAlgorithms() {
        for (Provider provider : Security.getProviders()) {
            for (Provider.Service service : provider.getServices()) {
                System.out.println(service.getAlgorithm());
            }
        }
    }

    public static void whenGetServicesWithFilter_thenGetAllCompatibleCipherAlgorithms() {
        List<String> algorithms = Arrays.stream(Security.getProviders())
          .flatMap(provider -> provider.getServices().stream())
          .filter(service -> "Cipher".equals(service.getType()))
          .map(Provider.Service::getAlgorithm)
          .collect(Collectors.toList());

        algorithms.forEach(System.out::println);
    }
}
