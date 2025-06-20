package com.realive.dto.sellerqna;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class SellerQnaRequestDTO {

    private String title;
    private String content;

}