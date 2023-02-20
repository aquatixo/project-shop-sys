package willms.member.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import willms.member.entity.RefreshToken;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    //Member ID 값으로 토큰을 가져오기 위해 findByKey
    Optional<RefreshToken> findByKey(String key);
}
