package com.realive.service.cart.view;

import com.realive.domain.customer.CartItem;
import com.realive.dto.cart.CartItemResponseDTO;
import com.realive.dto.cart.CartListResponseDTO;
import com.realive.dto.product.ProductResponseDTO;
import com.realive.repository.cart.CartItemRepository;
import com.realive.repository.customer.productview.ProductViewRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class CartViewServiceImpl implements CartViewService {

    private final CartItemRepository cartItemRepository;
    private final ProductViewRepository productViewRepository;

    @Override
    @Transactional(readOnly = true)
    public CartListResponseDTO getCart(Long customerId) {
        log.info("Fetching cart for customerId: {}", customerId);

        List<CartItem> cartItems = cartItemRepository.findByCustomer_Id(customerId);

        List<Long> productIds = cartItems.stream()
                .map(cartItem -> cartItem.getProduct().getId())
                .collect(Collectors.toList());


        Map<Long, ProductResponseDTO> productDetailMap = productIds.stream()
                .distinct() // 중복 ID 제거
                .map(id -> productViewRepository.findProductDetailById(id).orElse(null))
                .filter(dto -> dto != null)
                .collect(Collectors.toMap(ProductResponseDTO::getId, dto -> dto));

        List<CartItemResponseDTO> itemDTOs = cartItems.stream()
                .map(cartItem -> {
                    ProductResponseDTO productDetailDto = productDetailMap.get(cartItem.getProduct().getId());

                    if (productDetailDto == null) {
                        log.warn("Product detail not found for cart item productId: {}", cartItem.getProduct().getId());
                        // 상품 정보가 없는 경우 기본값으로 응답 (또는 예외 처리)
                        return CartItemResponseDTO.builder()
                                .cartItemId(cartItem.getId())
                                .productId(cartItem.getProduct().getId())
                                .productName("[상품 없음]")
                                .quantity(cartItem.getQuantity())
                                .productPrice(0)
                                .productImage(null)
                                .totalPrice(0)
                                .cartCreatedAt(cartItem.getCreatedAt())
                                .build();
                    }
                    return CartItemResponseDTO.from(cartItem, productDetailDto);
                })
                .collect(Collectors.toList());

        CartListResponseDTO cartResponse = CartListResponseDTO.from(itemDTOs);

        return cartResponse;
    }
}