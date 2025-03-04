import { ComponentFixture, TestBed } from '@angular/core/testing';
import { EspaceMedecinPage } from './espace-medecin.page';

describe('EspaceMedecinPage', () => {
  let component: EspaceMedecinPage;
  let fixture: ComponentFixture<EspaceMedecinPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(EspaceMedecinPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
