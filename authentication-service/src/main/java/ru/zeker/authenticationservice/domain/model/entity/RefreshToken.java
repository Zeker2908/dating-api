package ru.zeker.authenticationservice.domain.model.entity;

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
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@RedisHash("refresh_tokens")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshToken implements Serializable {

    @Id
    private String token;

    @Indexed
    private UUID userId;

    private Date expiryDate;

    @TimeToLive(unit = TimeUnit.SECONDS)
    private Long ttl;
}

