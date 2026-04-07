package com.example.archivage_Doc.Mappers;

import com.example.archivage_Doc.DTOs.UserDTO;
import com.example.archivage_Doc.Entities.User;
import com.example.archivage_Doc.Entities.UserRole;
import com.example.archivage_Doc.Enums.Permission;
import org.mapstruct.*;

import java.util.Set;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(target = "permissions", source = "userRoles", qualifiedByName = "userRolesToStrings")
    UserDTO toDTO(User user);

    @Mapping(target = "password", ignore = true)
    @Mapping(target = "userRoles", ignore = true)
    User toEntity(UserDTO userDTO);

    @Named("userRolesToStrings")
    default Set<String> userRolesToStrings(Set<UserRole> userRoles) {
        if (userRoles == null) return null;
        return userRoles.stream()
                .flatMap(userRole -> userRole.getPermissions().stream())
                .map(Permission::name)
                .collect(Collectors.toSet());
    }
}
