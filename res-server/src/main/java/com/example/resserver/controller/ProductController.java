package com.example.resserver.controller;




import com.example.resserver.entity.Product;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController

public class ProductController {

    private List<Product> products = new ArrayList<>();

    public ProductController() {
        products.add(Product.from("Men's Shoes (White)", "White color men's shoes", 100, "USD"));
        products.add(Product.from("TShirt (Blue)", "Blue color t-shirt", 55, "USD"));
        products.add(Product.from("TShirt (White)", "White color t-shirt", 50, "USD"));
        products.add(Product.from("Short (White)", "White color short", 60, "USD"));
        products.add(Product.from("Short (Black)", "Black color short", 55, "USD"));
    }
    //资源接口
    @GetMapping("/products")
    public List<Product> getProducts() {
        return products;
    }

    //获取用户信息
    @GetMapping(value = "/sso/user")
    public Map<String, String> user(Principal principal) {
        if (principal != null) {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("name", principal.getName());
            return map;
        }
        return null;
    }

}