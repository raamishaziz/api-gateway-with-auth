package api.gateway.security.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import api.gateway.security.model.Role;
import api.gateway.security.model.Token;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {

    private Long id;
    private String password;
    private String email;
    private String firstName;
    private String middleName;
    private String lastName;
    private Role userType;
    private List<Token> tokens;
    private String role;
    private String active;
}
