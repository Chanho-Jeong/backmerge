package com.realive.controller.seller;

import com.realive.domain.seller.Seller;
import com.realive.dto.seller.SellerDashboardResponseDTO;
import com.realive.service.seller.SellerDashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 판매자 대시보드 API
 * - 등록 상품 수
 * - 미답변 QnA 수
 * - 오늘 등록된 상품 수
 * - 총 QnA 수
 * - 진행 중인 주문 수
 */
@RestController
@RequestMapping("/api/seller/dashboard")
@RequiredArgsConstructor
public class SellerDashboardController {

    private final SellerDashboardService dashboardService;

    @GetMapping
    public ResponseEntity<SellerDashboardResponseDTO> getDashboard(Authentication authentication) {
        Seller seller = (Seller) authentication.getPrincipal(); // SecurityContext에서 Seller 추출
        SellerDashboardResponseDTO dashboardInfo = dashboardService.getDashboardInfo(seller.getId());
        return ResponseEntity.ok(dashboardInfo);
    }
}