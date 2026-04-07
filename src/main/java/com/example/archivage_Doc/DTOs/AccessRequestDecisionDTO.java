package com.example.archivage_Doc.DTOs;

import com.example.archivage_Doc.Enums.RequestStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessRequestDecisionDTO {
    private RequestStatus status;
    private String comments;
} 