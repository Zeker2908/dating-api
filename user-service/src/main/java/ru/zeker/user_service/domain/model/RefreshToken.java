package ru.zeker.user_service.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

import java.io.Serializable;
import java.util.Date;

@RedisHash("RefreshToken")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshToken implements Serializable {

    @Id
    private String token;

    @Indexed
    private Long userId;

    private Boolean revoked;

    private Date expiryDate;

    @TimeToLive
    private Long ttl;
}

