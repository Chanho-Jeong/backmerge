package com.realive.controller.product;

import com.realive.dto.product.ProductRequestDto;
import com.realive.dto.product.ProductResponseDto;
import com.realive.dto.product.ProductSearchCondition;
import com.realive.domain.seller.Seller;
import com.realive.dto.page.PageResponseDTO;
import com.realive.dto.product.ProductListDto;
import com.realive.service.product.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;



@RestController
@RequiredArgsConstructor
@RequestMapping("/api/seller/products")
public class ProductController {

    private final ProductService productService;
    

    // 🔽 상품 등록
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Long> createProduct(
            @ModelAttribute ProductRequestDto dto,
            @AuthenticationPrincipal Seller seller
    ) {
        Long sellerId = seller.getId();
        Long id = productService.createProduct(dto, sellerId);
        return ResponseEntity.ok(id);
    }

    // 🔽 상품 수정
    @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> updateProduct(
            @PathVariable Long id,
            @ModelAttribute ProductRequestDto dto,
            @AuthenticationPrincipal Seller seller
    ) {
        Long sellerId = seller.getId();
        productService.updateProduct(id, dto, sellerId);
        return ResponseEntity.ok().build();
    }

    // 🔽 상품 삭제
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteProduct(
            @PathVariable Long id,
            @AuthenticationPrincipal Seller seller
    ) {
        Long sellerId = seller.getId();
        productService.deleteProduct(id, sellerId);
        return ResponseEntity.ok().build();
    }

    // 🔽 상품 목록 조회 (판매자 전용)
    @GetMapping
    public ResponseEntity<PageResponseDTO<ProductListDto>> getMyProducts(
            @AuthenticationPrincipal Seller seller,
            @ModelAttribute ProductSearchCondition condition) {

        Long sellerId = seller.getId();
        PageResponseDTO<ProductListDto> response = productService.getProductsBySeller(sellerId, condition);

        return ResponseEntity.ok(response);
    }

    // 🔽 단일 상품 상세 조회 (공개 API 가능)
    @GetMapping("/{id}")
    public ResponseEntity<ProductResponseDto> getProductDetail(@PathVariable Long id) {
        ProductResponseDto dto = productService.getProductDetail(id);
        return ResponseEntity.ok(dto);
    }
}