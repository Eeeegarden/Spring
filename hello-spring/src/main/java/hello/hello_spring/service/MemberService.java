package hello.hello_spring.service;

import hello.hello_spring.domain.Member;
import hello.hello_spring.repository.MemberRepository;
import hello.hello_spring.repository.MemoryMemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Transactional
public class MemberService {
    private final MemberRepository memberrepository;

    public MemberService(MemberRepository memberrepository) {
        this.memberrepository = memberrepository;
    }

    /**
     * 회원가입
     */
    public Long join(Member member){
        validateDuplicateMember(member); // 중복 회원 검증
        memberrepository.save(member);
        return member.getId();
    }

    private void validateDuplicateMember(Member member) {
        memberrepository.findByName(member.getName())
            .ifPresent(m -> {
                throw new IllegalStateException("이미 존재하는 회원입니다.");
            });
    }

    /**
     * 전체 회원 조회
     */
    public List<Member> findMembers(){
        return memberrepository.findAll();
    }

    public Optional<Member> findOne(Long memberId){
        return memberrepository.findById(memberId);
    }


}
